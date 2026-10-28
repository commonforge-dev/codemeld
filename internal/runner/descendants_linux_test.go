//go:build linux

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireSetsid(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skipf("setsid not available: %v", err)
	}
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitGone(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !processGone(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still alive", what, pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func requireMarker(t *testing.T, pid int, id string) {
	t.Helper()
	path := "/proc/" + strconv.Itoa(pid) + "/environ"
	waitUntil(t, fmt.Sprintf("pid %d to carry %s=%s", pid, RunMarkerEnv, id), func() bool {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("host restriction: cannot read %s, so marker lookup cannot be exercised: %v", path, err)
		}
		return slices.Contains(strings.Split(string(data), "\x00"), RunMarkerEnv+"="+id)
	})
}

type apiOutcome struct {
	stdout string
	exit   int
	err    error
}

var runnerAPIs = []string{"Exec", "ExecBounded", "Pipeline"}

func runAPI(t *testing.T, api string, ctx context.Context, spec RunSpec) apiOutcome {
	r := DirectExecRunner{}
	switch api {
	case "Exec":
		res, err := r.Exec(ctx, spec)
		return apiOutcome{string(res.Stdout), res.ExitCode, err}
	case "ExecBounded":
		res, err := r.ExecBounded(ctx, spec, 1<<16)
		return apiOutcome{string(res.Stdout), res.ExitCode, err}
	}
	results, err := r.Pipeline(ctx, []RunSpec{pipelineSpec(t, map[string]string{helperBlock: "1"}), spec}, 1<<16)
	if len(results) != 2 {
		return apiOutcome{err: fmt.Errorf("Pipeline returned %d results, want 2 (err %v)", len(results), err)}
	}
	return apiOutcome{string(results[1].Stdout), results[1].ExitCode, err}
}

func cancelOutcomeErr(api string, got apiOutcome) error {
	if api == "Pipeline" && errors.Is(got.err, context.Canceled) {
		return nil
	}
	if api == "Pipeline" {
		return fmt.Errorf("Pipeline error = %v, want it to wrap context.Canceled", got.err)
	}
	return got.err
}

func awaitCanceled(t *testing.T, api string, cancel context.CancelFunc, done <-chan apiOutcome) apiOutcome {
	t.Helper()
	began := time.Now()
	cancel()
	select {
	case got := <-done:
		if elapsed := time.Since(began); elapsed > outputGrace+time.Second {
			t.Fatalf("%s returned %v after cancellation, want within the %v grace plus a margin", api, elapsed, outputGrace)
		}
		if err := cancelOutcomeErr(api, got); err != nil {
			t.Fatal(err)
		}
		return got
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return after cancellation", api)
		return apiOutcome{}
	}
}

func TestDirectExecRunner_CancelKillsEscapedDescendants(t *testing.T) {
	requireSetsid(t)
	sh := shPath(t)
	middle := writeScript(t, `echo $$ > "$2"
setsid sh -c 'echo $$ > "$1"; exec sleep 30' sh "$1" &
`)
	routes := map[string]string{
		"parent chain without marker": `echo $$ > "$2"; printf before
env -u ` + RunMarkerEnv + ` setsid sh -c 'echo $$ > "$1"; exec sleep 30' sh "$1" &
wait`,
		"orphan marker": `echo $$ > "$2"; printf before
sh "$3" "$1" "$4"
sleep 30`,
	}
	for route, script := range routes {
		for _, api := range runnerAPIs {
			t.Run(route+"/"+api, func(t *testing.T) {
				dir := t.TempDir()
				escapedFile, rootFile, middleFile := filepath.Join(dir, "escaped"), filepath.Join(dir, "root"), filepath.Join(dir, "middle")
				id := DirectExecRunner{}.NewInvocationID()
				spec := RunSpec{InvocationID: id, Argv: []string{sh, "-c", script, "sh", escapedFile, rootFile, middle, middleFile}}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan apiOutcome, 1)
				go func() { done <- runAPI(t, api, ctx, spec) }()

				root := waitPID(t, rootFile)
				escaped := waitPID(t, escapedFile)
				if route == "orphan marker" {
					mid := waitPID(t, middleFile)
					waitUntil(t, "the middle parent to exit", func() bool { return processGone(mid) })
					waitUntil(t, "the escaped process to be reparented", func() bool {
						ppid, ok := procField(escaped, 1)
						return ok && ppid != strconv.Itoa(mid) && ppid != strconv.Itoa(root)
					})
					requireMarker(t, escaped, id)
				} else {
					waitUntil(t, "the escaped child's parent chain", func() bool {
						ppid, ok := procField(escaped, 1)
						return ok && ppid == strconv.Itoa(root)
					})
					if data, err := os.ReadFile("/proc/" + strconv.Itoa(escaped) + "/environ"); err == nil && strings.Contains(string(data), RunMarkerEnv+"=") {
						t.Fatalf("escaped child still carries %s; this route must not depend on it", RunMarkerEnv)
					}
				}

				got := awaitCanceled(t, api, cancel, done)
				if got.stdout != "before" {
					t.Fatalf("stdout = %q, want the output printed before the kill", got.stdout)
				}
				waitGone(t, escaped, "escaped descendant")
			})
		}
	}
}

func TestDirectExecRunner_CancelAfterRootExitFindsMarkedOrphan(t *testing.T) {
	requireSetsid(t)
	script := `echo $$ > "$2"; printf before
setsid sh -c 'echo $$ > "$1"; exec sleep 30' sh "$1" &`
	for _, api := range runnerAPIs {
		t.Run(api, func(t *testing.T) {
			dir := t.TempDir()
			escapedFile, rootFile := filepath.Join(dir, "escaped"), filepath.Join(dir, "root")
			id := DirectExecRunner{}.NewInvocationID()
			spec := RunSpec{InvocationID: id, Argv: []string{shPath(t), "-c", script, "sh", escapedFile, rootFile}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan apiOutcome, 1)
			go func() { done <- runAPI(t, api, ctx, spec) }()

			root := waitPID(t, rootFile)
			escaped := waitPID(t, escapedFile)
			waitUntil(t, "the root to exit", func() bool { return processGone(root) })
			requireMarker(t, escaped, id)
			awaitCanceled(t, api, cancel, done)
			waitGone(t, escaped, "orphan left behind by the exited root")
		})
	}
}

func TestDirectExecRunner_CancelLeavesOtherInvocationsAlone(t *testing.T) {
	requireSetsid(t)
	script := `setsid sh -c 'echo $$ > "$1"; exec sleep 30' sh "$1" >/dev/null 2>&1 &
wait`
	type call struct {
		cancel  context.CancelFunc
		done    chan apiOutcome
		escaped int
	}
	start := func() call {
		file := filepath.Join(t.TempDir(), "escaped")
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		c := call{cancel: cancel, done: make(chan apiOutcome, 1)}
		spec := RunSpec{InvocationID: DirectExecRunner{}.NewInvocationID(), Argv: []string{shPath(t), "-c", script, "sh", file}}
		go func() { c.done <- runAPI(t, "Exec", ctx, spec) }()
		c.escaped = waitPID(t, file)
		return c
	}
	a, b := start(), start()
	awaitCanceled(t, "Exec", a.cancel, a.done)
	waitGone(t, a.escaped, "cancelled call's descendant")
	if processGone(b.escaped) {
		t.Fatal("cancelling one call killed the other call's descendant")
	}
	awaitCanceled(t, "Exec", b.cancel, b.done)
	waitGone(t, b.escaped, "second call's descendant")
}

func TestDirectExecRunner_CancelSparesOlderMarkerMatches(t *testing.T) {
	requireSetsid(t)
	id := DirectExecRunner{}.NewInvocationID()
	older := exec.Command("sleep", "30")
	older.Env = append(os.Environ(), RunMarkerEnv+"="+id)
	if err := older.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = older.Process.Kill(); _ = older.Wait() })
	time.Sleep(50 * time.Millisecond)

	file := filepath.Join(t.TempDir(), "escaped")
	middle := writeScript(t, `setsid sh -c 'echo $$ > "$1"; exec sleep 30' sh "$1" >/dev/null 2>&1 &
`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan apiOutcome, 1)
	spec := RunSpec{InvocationID: id, Argv: []string{shPath(t), "-c", `sh "$2" "$1"; sleep 30`, "sh", file, middle}}
	go func() { done <- runAPI(t, "Exec", ctx, spec) }()
	escaped := waitPID(t, file)
	requireMarker(t, escaped, id)
	awaitCanceled(t, "Exec", cancel, done)
	waitGone(t, escaped, "marked orphan")
	if processGone(older.Process.Pid) {
		t.Fatal("a marker match older than the root was killed")
	}
}

func TestDirectExecRunner_RunMarkerIsOnePerInvocation(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dumpedEnv := func(stderr []byte) []string {
		return slices.DeleteFunc(strings.Split(string(stderr), "\n"), func(s string) bool { return s == "" })
	}
	supplied := []string{helperEnv + "=1", helperDumpEnv + "=1", RunMarkerEnv + "=supplied-1", "KEEP=1", RunMarkerEnv + "=supplied-2"}
	newSpec := func(env []string) RunSpec {
		return RunSpec{InvocationID: DirectExecRunner{}.NewInvocationID(), Argv: []string{exe, "-test.run=^$"}, Env: env}
	}
	check := func(t *testing.T, spec RunSpec, stderr []byte) {
		t.Helper()
		env := dumpedEnv(stderr)
		markers := slices.DeleteFunc(slices.Clone(env), func(e string) bool { return !strings.HasPrefix(e, RunMarkerEnv+"=") })
		if !slices.Equal(markers, []string{RunMarkerEnv + "=" + spec.InvocationID}) {
			t.Fatalf("markers = %q, want exactly this invocation's id %s", markers, spec.InvocationID)
		}
		if spec.Env != nil && !slices.Contains(env, "KEEP=1") {
			t.Fatalf("env %q lost a supplied variable", env)
		}
	}
	r := DirectExecRunner{}
	t.Run("supplied duplicates", func(t *testing.T) {
		spec := newSpec(slices.Clone(supplied))
		res, err := r.Exec(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		check(t, spec, res.Stderr)
		spec = newSpec(slices.Clone(supplied))
		bounded, err := r.ExecBounded(context.Background(), spec, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		check(t, spec, bounded.Stderr)
		if !slices.Equal(spec.Env, supplied) {
			t.Fatalf("caller Env mutated: %q", spec.Env)
		}
		first, second := newSpec(slices.Clone(supplied)), newSpec(slices.Clone(supplied))
		results, err := r.Pipeline(context.Background(), []RunSpec{first, second}, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		check(t, first, results[0].Stderr)
		check(t, second, results[1].Stderr)
	})
	t.Run("inherited marker", func(t *testing.T) {
		t.Setenv(helperEnv, "1")
		t.Setenv(helperDumpEnv, "1")
		t.Setenv(RunMarkerEnv, "inherited")
		spec := newSpec(nil)
		res, err := r.Exec(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		check(t, spec, res.Stderr)
		if os.Getenv(RunMarkerEnv) != "inherited" {
			t.Fatal("the parent environment was changed")
		}
	})
	t.Run("confined fixed environment", func(t *testing.T) {
		fixed, err := FixedEnvironment("/home/u", t.TempDir(), "", FixedPATH, []string{helperEnv + "=1", helperDumpEnv + "=1"})
		if err != nil {
			t.Fatal(err)
		}
		spec := newSpec(slices.Clone(fixed))
		res, err := r.ExecBounded(context.Background(), spec, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		got, want := dumpedEnv(res.Stderr), append(slices.Clone(fixed), RunMarkerEnv+"="+spec.InvocationID)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("confined env = %q, want the fixed table plus one marker %q", got, want)
		}
		if !slices.Equal(spec.Env, fixed) {
			t.Fatalf("caller Env mutated: %q", spec.Env)
		}
	})
}

func startSleeper(t *testing.T, env []string) (*exec.Cmd, procID) {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	st, ok := readProcStat(cmd.Process.Pid)
	if !ok {
		t.Fatalf("cannot read /proc/%d/stat", cmd.Process.Pid)
	}
	return cmd, procID{pid: cmd.Process.Pid, start: st.start}
}

func TestSignal_SkipsAChangedIdentity(t *testing.T) {
	_, id := startSleeper(t, nil)
	signal([]procID{{pid: id.pid, start: id.start + 1}}, map[procID]bool{})
	time.Sleep(50 * time.Millisecond)
	if processGone(id.pid) {
		t.Fatal("a pid whose start time changed was signaled")
	}
	signal([]procID{id}, map[procID]bool{})
	waitGone(t, id.pid, "the matching identity")
}

func TestKillEscaped_NeverTargetsAnotherLiveRoot(t *testing.T) {
	rootID := DirectExecRunner{}.NewInvocationID()
	rootCmd, _ := startSleeper(t, nil)
	root := registerRoot(rootCmd.Process.Pid)
	defer unregisterRoot(root)
	time.Sleep(20 * time.Millisecond)
	otherCmd, _ := startSleeper(t, append(os.Environ(), RunMarkerEnv+"="+rootID))
	requireMarker(t, otherCmd.Process.Pid, rootID)
	other := registerRoot(otherCmd.Process.Pid)

	_ = killEscaped(root, rootID, true)
	waitGone(t, root.pid, "the cancelled root")
	time.Sleep(50 * time.Millisecond)
	if processGone(other.pid) {
		t.Fatal("cleanup killed a different live invocation's root")
	}
	unregisterRoot(other)
	_ = killEscaped(root, rootID, false)
	waitGone(t, other.pid, "the marker match once it is no longer a live root")
}

func TestDirectExecRunner_CancelUnregistersRootAfterCleanup(t *testing.T) {
	requireSetsid(t)
	file := filepath.Join(t.TempDir(), "escaped")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan apiOutcome, 1)
	spec := RunSpec{InvocationID: DirectExecRunner{}.NewInvocationID(), Argv: []string{shPath(t), "-c", `setsid sh -c 'echo $$ > "$1"; exec sleep 30' sh "$1" & wait`, "sh", file}}
	go func() { done <- runAPI(t, "ExecBounded", ctx, spec) }()
	escaped := waitPID(t, file)
	awaitCanceled(t, "ExecBounded", cancel, done)
	waitGone(t, escaped, "escaped child")
	liveRoots.Lock()
	defer liveRoots.Unlock()
	if len(liveRoots.ids) != 0 {
		t.Fatalf("live roots after the call returned: %v", liveRoots.ids)
	}
}

func TestKillEscaped_ObsoleteRootSparesTheGroupItsPidNowNames(t *testing.T) {
	id := DirectExecRunner{}.NewInvocationID()
	replacement, current := startSleeper(t, nil)
	orphan, _ := startSleeper(t, append(os.Environ(), RunMarkerEnv+"="+id))
	requireMarker(t, orphan.Process.Pid, id)
	inv := &invocation{id: id, root: rootIdentity{procID: procID{pid: current.pid, start: current.start - 1}, known: true}}

	_ = inv.cancel()
	waitGone(t, orphan.Process.Pid, "the original invocation's marked orphan")
	time.Sleep(50 * time.Millisecond)
	if processGone(replacement.Process.Pid) {
		t.Fatal("cleanup for an obsolete root identity killed the live process group its pid now names")
	}
}

func TestDirectExecRunner_CancelAfterRootReapSkipsItsGroup(t *testing.T) {
	requireSetsid(t)
	script := `echo $$ > "$2"; printf before
setsid sh -c 'echo $$ > "$1"; exec sleep 30' sh "$1" &
while [ ! -e "$3" ]; do sleep 0.01; done`
	for _, api := range runnerAPIs {
		t.Run(api, func(t *testing.T) {
			dir := t.TempDir()
			escapedFile, rootFile, goFile := filepath.Join(dir, "escaped"), filepath.Join(dir, "root"), filepath.Join(dir, "go")
			id := DirectExecRunner{}.NewInvocationID()
			spec := RunSpec{InvocationID: id, Argv: []string{shPath(t), "-c", script, "sh", escapedFile, rootFile, goFile}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan apiOutcome, 1)
			go func() { done <- runAPI(t, api, ctx, spec) }()

			root := waitPID(t, rootFile)
			escaped := waitPID(t, escapedFile)
			member := exec.Command("sleep", "30")
			member.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: root}
			if err := member.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = member.Process.Kill(); _ = member.Wait() })
			if err := os.WriteFile(goFile, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			waitUntil(t, "the root to be reaped", func() bool {
				_, ok := procField(root, 0)
				return !ok
			})
			requireMarker(t, escaped, id)

			awaitCanceled(t, api, cancel, done)
			waitGone(t, escaped, "the marked orphan of the reaped root")
			time.Sleep(50 * time.Millisecond)
			if processGone(member.Process.Pid) {
				t.Fatal("cancellation after the root was reaped signaled the process group its pid named")
			}
		})
	}
}
