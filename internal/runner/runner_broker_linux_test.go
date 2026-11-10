package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type testLaunch struct {
	own, helper *os.File
	inodes      []uint64
	startErr    error
	beforeStart func()
	mu          sync.Mutex
	started     int
	closed      int
	stop        chan struct{}
	worker      chan struct{}
}

func newTestLaunch(t *testing.T) *testLaunch {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	l := &testLaunch{own: os.NewFile(uintptr(fds[0]), "own"), helper: os.NewFile(uintptr(fds[1]), "helper"), stop: make(chan struct{})}
	for _, fd := range fds {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		l.inodes = append(l.inodes, st.Ino)
	}
	t.Cleanup(l.Close)
	return l
}

func (l *testLaunch) HelperChannel() *os.File { return l.helper }

func (l *testLaunch) Started() error {
	if l.beforeStart != nil {
		l.beforeStart()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.started++
	_ = l.helper.Close()
	if l.startErr != nil {
		return l.startErr
	}
	if _, err := l.own.Write([]byte{'R'}); err != nil {
		return err
	}
	worker := make(chan struct{})
	l.worker = worker
	go func() {
		defer close(worker)
		<-l.stop
	}()
	return nil
}

func (l *testLaunch) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed++
	_ = l.helper.Close()
	_ = l.own.Close()
	if l.closed == 1 {
		close(l.stop)
	}
	if l.worker != nil {
		<-l.worker
	}
}

func (l *testLaunch) startedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.started
}

func withLaunches(t *testing.T, specs []RunSpec) []*testLaunch {
	t.Helper()
	launches := make([]*testLaunch, len(specs))
	for i := range specs {
		launches[i] = newTestLaunch(t)
		specs[i].Helper = launches[i]
	}
	return launches
}

func openSocketInodes(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	open := map[string]bool{}
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && strings.HasPrefix(target, "socket:") {
			open[target] = true
		}
	}
	return open
}

func assertReleased(t *testing.T, launches []*testLaunch) {
	t.Helper()
	open := openSocketInodes(t)
	for i, l := range launches {
		l.mu.Lock()
		closed, worker := l.closed, l.worker
		l.mu.Unlock()
		if closed == 0 {
			t.Errorf("launch %d: never closed", i)
		}
		if worker != nil {
			select {
			case <-worker:
			default:
				t.Errorf("launch %d: broker worker still running after return", i)
			}
		}
		for _, ino := range l.inodes {
			if open[fmt.Sprintf("socket:[%d]", ino)] {
				t.Errorf("launch %d: socket %d still open in the parent", i, ino)
			}
		}
	}
}

type launchPath struct {
	name   string
	stages int
	run    func(ctx context.Context, specs []RunSpec) ([]int, error)
}

func launchPaths() []launchPath {
	r := DirectExecRunner{}
	return []launchPath{
		{"Exec", 1, func(ctx context.Context, specs []RunSpec) ([]int, error) {
			res, err := r.Exec(ctx, specs[0])
			return []int{res.ExitCode}, err
		}},
		{"ExecBounded", 1, func(ctx context.Context, specs []RunSpec) ([]int, error) {
			res, err := r.ExecBounded(ctx, specs[0], 1024)
			return []int{res.ExitCode}, err
		}},
		{"Pipeline", 2, func(ctx context.Context, specs []RunSpec) ([]int, error) {
			results, err := r.Pipeline(ctx, specs, 1024)
			codes := make([]int, len(results))
			for i, res := range results {
				codes[i] = res.ExitCode
			}
			return codes, err
		}},
	}
}

func runWithin(t *testing.T, ctx context.Context, path launchPath, specs []RunSpec) ([]int, error) {
	t.Helper()
	type outcome struct {
		codes []int
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		codes, err := path.run(ctx, specs)
		done <- outcome{codes, err}
	}()
	select {
	case got := <-done:
		return got.codes, got.err
	case <-time.After(20 * time.Second):
		t.Fatalf("%s did not return within 20s", path.name)
		return nil, nil
	}
}

func channelSpecs(t *testing.T, n int, extra map[string]string) []RunSpec {
	t.Helper()
	env := map[string]string{helperChannel: "1"}
	for k, v := range extra {
		env[k] = v
	}
	specs := make([]RunSpec, n)
	for i := range specs {
		specs[i] = pipelineSpec(t, env)
	}
	return specs
}

func TestHelperLaunch_ChannelIsDescriptorThreeAndClosedAfterExit(t *testing.T) {
	for _, path := range launchPaths() {
		t.Run(path.name, func(t *testing.T) {
			specs := channelSpecs(t, path.stages, nil)
			launches := withLaunches(t, specs)
			codes, err := runWithin(t, context.Background(), path, specs)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			for i, code := range codes {
				if code != 0 {
					t.Errorf("stage %d exit %d, want 0 (released on descriptor 3 after start)", i, code)
				}
			}
			for i, l := range launches {
				if n := l.startedCount(); n != 1 {
					t.Errorf("launch %d started %d times, want 1", i, n)
				}
			}
			assertReleased(t, launches)
		})
	}
}

func TestHelperLaunch_ValidationFailureClosesTheLaunch(t *testing.T) {
	for _, path := range launchPaths() {
		t.Run(path.name, func(t *testing.T) {
			specs := channelSpecs(t, path.stages, nil)
			specs[0].InvocationID = "not-a-uuid"
			launches := withLaunches(t, specs)
			if _, err := runWithin(t, context.Background(), path, specs); err == nil {
				t.Fatal("err = nil, want a validation error")
			}
			assertReleased(t, launches)
		})
	}
}

func TestHelperLaunch_FailedStartClosesTheLaunch(t *testing.T) {
	for _, path := range launchPaths() {
		t.Run(path.name, func(t *testing.T) {
			specs := channelSpecs(t, path.stages, nil)
			specs[0] = missingBinarySpec()
			launches := withLaunches(t, specs)
			codes, err := runWithin(t, context.Background(), path, specs)
			if err != nil || codes[0] != -1 {
				t.Fatalf("codes %v err %v, want stage 0 to fail to launch", codes, err)
			}
			if n := launches[0].startedCount(); n != 0 {
				t.Errorf("unstarted launch had Started called %d times", n)
			}
			assertReleased(t, launches)
		})
	}
}

func TestHelperLaunch_SetupFailureKillsTheProcessAndClosesTheLaunch(t *testing.T) {
	refused := errors.New("handoff refused")
	for _, path := range launchPaths() {
		t.Run(path.name, func(t *testing.T) {
			specs := channelSpecs(t, path.stages, nil)
			launches := withLaunches(t, specs)
			for _, l := range launches {
				l.startErr = refused
			}
			if _, err := runWithin(t, context.Background(), path, specs); !errors.Is(err, refused) {
				t.Fatalf("err = %v, want the setup failure", err)
			}
			assertReleased(t, launches)
		})
	}
}

func TestHelperLaunch_PipelineSetupFailureEndsAReleasedBlockingSibling(t *testing.T) {
	refused := errors.New("handoff refused")
	for failing := range 2 {
		t.Run(fmt.Sprintf("stage%dFails", failing), func(t *testing.T) {
			sibling := 1 - failing
			specs := channelSpecs(t, 2, map[string]string{helperBlock: "1"})
			launches := withLaunches(t, specs)
			launches[failing].startErr = refused
			launches[failing].beforeStart = func() {
				for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
					launches[sibling].mu.Lock()
					released := launches[sibling].worker != nil
					launches[sibling].mu.Unlock()
					if released {
						return
					}
				}
			}
			r := DirectExecRunner{}
			done := make(chan struct{})
			var results []PipelineResult
			var err error
			go func() {
				defer close(done)
				results, err = r.Pipeline(context.Background(), specs, 1024)
			}()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("Pipeline did not return after a stage's helper setup failed")
			}
			if !errors.Is(err, refused) {
				t.Fatalf("err = %v, want the setup failure", err)
			}
			if launches[sibling].worker == nil {
				t.Fatalf("stage %d was never released", sibling)
			}
			if results[failing].PipelineErrCategory != PipelineFailureInternal {
				t.Errorf("failing stage category %q, want %q", results[failing].PipelineErrCategory, PipelineFailureInternal)
			}
			if results[sibling].ExitCode != -1 {
				t.Errorf("released sibling exit %d, want -1 (killed and reaped)", results[sibling].ExitCode)
			}
			assertReleased(t, launches)
		})
	}
}

func TestHelperLaunch_CancellationClosesEveryLaunch(t *testing.T) {
	for _, path := range launchPaths() {
		t.Run(path.name, func(t *testing.T) {
			specs := channelSpecs(t, path.stages, map[string]string{helperBlock: "1"})
			launches := withLaunches(t, specs)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					all := true
					for _, l := range launches {
						all = all && l.startedCount() == 1
					}
					if all {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				cancel()
			}()
			_, _ = runWithin(t, ctx, path, specs)
			for i, l := range launches {
				if n := l.startedCount(); n != 1 {
					t.Errorf("launch %d started %d times before cancellation, want 1", i, n)
				}
			}
			assertReleased(t, launches)
		})
	}
}

const captureChildEnv = "CODEMELD_RUNNER_CAPTURE_CHILD"

func TestHelperLaunch_CaptureSetupFailureClosesTheLaunch(t *testing.T) {
	if name := os.Getenv(captureChildEnv); name != "" {
		captureFailureChild(t, name)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ExecBounded", "Pipeline"} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestHelperLaunch_CaptureSetupFailureClosesTheLaunch$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), captureChildEnv+"="+name)
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "capture child ran") {
				t.Fatalf("child: %v\n%s", err, out)
			}
		})
	}
}

func captureFailureChild(t *testing.T, name string) {
	var path launchPath
	for _, p := range launchPaths() {
		if p.name == name {
			path = p
		}
	}
	specs := channelSpecs(t, path.stages, nil)
	launches := withLaunches(t, specs)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	closeFiles(r, w)
	fillers := fillDescriptorTable(t)
	_, err = path.run(context.Background(), specs)
	for _, fd := range fillers {
		_ = syscall.Close(fd)
	}
	if err == nil || !strings.Contains(err.Error(), "setup") {
		t.Fatalf("err = %v, want a capture setup failure", err)
	}
	assertReleased(t, launches)
	t.Log("capture child ran")
}

func fillDescriptorTable(t *testing.T) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	highest := 0
	for _, e := range entries {
		var fd int
		if _, err := fmt.Sscan(e.Name(), &fd); err == nil {
			highest = max(highest, fd)
		}
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	lim.Cur = uint64(highest + 1)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	var fillers []int
	for {
		fd, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if errors.Is(err, syscall.EMFILE) {
			return fillers
		}
		if err != nil {
			t.Fatal(err)
		}
		fillers = append(fillers, fd)
	}
}
